with open("src/lib.rs", "r") as f:
    content = f.read()

search = """fn request_delivery_route(action: &Action, target: &TargetRef) -> DeliveryRoute {
    match (action, target) {
        (
            Action::Invoke
            | Action::SetValue { .. }
            | Action::SelectText { .. }
            | Action::PerformSecondaryAction { .. },
            TargetRef::Element { .. },
        ) => DeliveryRoute::TargetAddressed,
        (Action::Scroll { .. }, TargetRef::Element { .. }) => {
            if cfg!(target_os = "macos") {
                native_pointer_delivery_route()
            } else {
                DeliveryRoute::TargetAddressed
            }
        }
        (_, TargetRef::Element { .. }) => native_pointer_delivery_route(),
        _ => DeliveryRoute::Pointer,
    }
}"""

replace = """fn request_delivery_route(action: &Action, target: &TargetRef) -> DeliveryRoute {
    let TargetRef::Element { .. } = target else {
        return DeliveryRoute::Pointer;
    };

    let route = action_delivery_route(action);
    if matches!(route, DeliveryRoute::TargetAddressed)
        || (matches!(action, Action::Scroll { .. }) && !cfg!(target_os = "macos"))
    {
        DeliveryRoute::TargetAddressed
    } else {
        native_pointer_delivery_route()
    }
}"""

content = content.replace(search, replace)

with open("src/lib.rs", "w") as f:
    f.write(content)
